use std::{
    collections::HashMap,
    future::Future,
    sync::{Arc, Barrier, Mutex},
    thread,
};

use chrono::{DateTime, Duration, Utc};
use nazo_digital_credentials::CredentialFormat;
use nazo_openid4vci::{
    CredentialAccess, CredentialIdentifier, CredentialResponseEncoding, CredentialStoreError,
    CredentialStoreFuture, CredentialStorePort, DeferredCredential, DeferredCredentialClaim,
    IssuanceNotification, NonceRecord, NotificationEvent, NotificationHandle,
    StoredCredentialOffer, StoredCredentialResponse,
};
use serde_json::json;
use uuid::Uuid;

fn nonce_claim_ttl() -> Duration {
    Duration::minutes(5)
}

#[derive(Clone, Debug)]
struct NonceState {
    expires_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
    claim_id: Option<String>,
    claim_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
struct DeferredState {
    credential: DeferredCredential,
    consumed_at: Option<DateTime<Utc>>,
    claim_id: Option<String>,
    claim_expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug)]
struct NotificationState {
    handle: NotificationHandle,
    event: Option<NotificationEvent>,
}

#[derive(Default)]
struct State {
    nonces: HashMap<String, NonceState>,
    deferred: HashMap<(String, Uuid), DeferredState>,
    // Mirrors the database UNIQUE(token_id, request_digest) constraint.  The
    // issuance id remains part of the read-side identity check below.
    responses: HashMap<(Uuid, String), StoredCredentialResponse>,
    notifications: HashMap<(String, Uuid), NotificationState>,
}

#[derive(Clone, Default)]
struct TransitionStore {
    state: Arc<Mutex<State>>,
}

impl TransitionStore {
    fn nonce(&self, nonce_hash: &str) -> NonceState {
        self.state
            .lock()
            .unwrap()
            .nonces
            .get(nonce_hash)
            .cloned()
            .expect("nonce fixture exists")
    }

    fn deferred(&self, transaction_hash: &str, token_id: Uuid) -> Option<DeferredState> {
        self.state
            .lock()
            .unwrap()
            .deferred
            .get(&(transaction_hash.to_owned(), token_id))
            .cloned()
    }

    fn notification_count(&self) -> usize {
        self.state.lock().unwrap().notifications.len()
    }

    fn response_count(&self) -> usize {
        self.state.lock().unwrap().responses.len()
    }

    fn claim_nonce_locked(
        state: &mut State,
        nonce_hash: &str,
        claim_id: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(nonce) = state.nonces.get_mut(nonce_hash) else {
            return false;
        };
        if nonce.consumed_at.is_some() || nonce.expires_at <= now {
            return false;
        }
        if nonce
            .claim_expires_at
            .is_some_and(|claim_expires_at| claim_expires_at > now)
        {
            return false;
        }
        nonce.claim_id = Some(claim_id.to_owned());
        nonce.claim_expires_at = Some(now + nonce_claim_ttl());
        true
    }

    fn finalize_nonce_locked(
        state: &mut State,
        nonce_hash: &str,
        claim_id: &str,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(nonce) = state.nonces.get_mut(nonce_hash) else {
            return false;
        };
        if nonce.consumed_at.is_some()
            || nonce.expires_at <= now
            || nonce.claim_id.as_deref() != Some(claim_id)
        {
            return false;
        }
        nonce.consumed_at = Some(now);
        nonce.claim_id = None;
        nonce.claim_expires_at = None;
        true
    }

    fn store_notification_locked(
        state: &mut State,
        handle: &NotificationHandle,
    ) -> Result<(), CredentialStoreError> {
        let key = (handle.notification_id.clone(), handle.token_id);
        if state.notifications.contains_key(&key) {
            return Err(CredentialStoreError::InvalidTransition);
        }
        state.notifications.insert(
            key,
            NotificationState {
                handle: handle.clone(),
                event: None,
            },
        );
        Ok(())
    }

    fn store_response_locked(
        state: &mut State,
        response: &StoredCredentialResponse,
    ) -> Result<(), CredentialStoreError> {
        let key = (response.token_id, response.request_digest.clone());
        if state.responses.insert(key, response.clone()).is_some() {
            return Err(CredentialStoreError::InvalidTransition);
        }
        Ok(())
    }

    fn commit_nonce_with_side_effects(
        &self,
        nonce_hash: &str,
        claim_id: &str,
        handle: &NotificationHandle,
        response: Option<&StoredCredentialResponse>,
        now: DateTime<Utc>,
    ) -> Result<bool, CredentialStoreError> {
        let mut state = self.state.lock().unwrap();
        let nonce = state
            .nonces
            .get(nonce_hash)
            .ok_or(CredentialStoreError::InvalidTransition)?;
        if nonce.consumed_at.is_some()
            || nonce.expires_at <= now
            || nonce.claim_id.as_deref() != Some(claim_id)
        {
            return Ok(false);
        }
        if state
            .notifications
            .contains_key(&(handle.notification_id.clone(), handle.token_id))
        {
            return Err(CredentialStoreError::InvalidTransition);
        }
        if let Some(response) = response {
            let key = (response.token_id, response.request_digest.clone());
            if state.responses.contains_key(&key) {
                return Err(CredentialStoreError::InvalidTransition);
            }
        }
        Self::store_notification_locked(&mut state, handle)?;
        if let Some(response) = response {
            Self::store_response_locked(&mut state, response)?;
        }
        Ok(Self::finalize_nonce_locked(
            &mut state, nonce_hash, claim_id, now,
        ))
    }

    fn commit_deferred_with_side_effects(
        &self,
        credential: &DeferredCredential,
        claim: Option<(&str, &str)>,
        handle: Option<&NotificationHandle>,
        response: Option<&StoredCredentialResponse>,
        now: DateTime<Utc>,
    ) -> Result<(), CredentialStoreError> {
        let mut state = self.state.lock().unwrap();
        let key = (
            credential.transaction_hash.clone(),
            credential.access.token_id,
        );
        if state.deferred.contains_key(&key) {
            return Err(CredentialStoreError::InvalidTransition);
        }
        if let Some(handle) = handle
            && state
                .notifications
                .contains_key(&(handle.notification_id.clone(), handle.token_id))
        {
            return Err(CredentialStoreError::InvalidTransition);
        }
        if let Some(response) = response {
            let response_key = (response.token_id, response.request_digest.clone());
            if state.responses.contains_key(&response_key) {
                return Err(CredentialStoreError::InvalidTransition);
            }
        }
        if let Some((nonce_hash, claim_id)) = claim {
            let nonce = state
                .nonces
                .get(nonce_hash)
                .ok_or(CredentialStoreError::InvalidTransition)?;
            if nonce.consumed_at.is_some()
                || nonce.expires_at <= now
                || nonce.claim_id.as_deref() != Some(claim_id)
            {
                return Err(CredentialStoreError::InvalidTransition);
            }
        }
        state.deferred.insert(
            key,
            DeferredState {
                credential: credential.clone(),
                consumed_at: None,
                claim_id: None,
                claim_expires_at: None,
            },
        );
        if let Some(handle) = handle {
            Self::store_notification_locked(&mut state, handle)?;
        }
        if let Some(response) = response {
            Self::store_response_locked(&mut state, response)?;
        }
        if let Some((nonce_hash, claim_id)) = claim
            && !Self::finalize_nonce_locked(&mut state, nonce_hash, claim_id, now)
        {
            return Err(CredentialStoreError::InvalidTransition);
        }
        Ok(())
    }
}

impl CredentialStorePort for TransitionStore {
    fn upsert_access<'a>(
        &'a self,
        _: &'a str,
        _: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn offer<'a>(
        &'a self,
        _: Uuid,
        _: Uuid,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        Box::pin(async { Ok(None) })
    }

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: Option<&'a str>,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<
        'a,
        Result<Option<nazo_openid4vci::CredentialAuthorization>, CredentialStoreError>,
    > {
        Box::pin(async { Ok(None) })
    }

    fn issue_nonce<'a>(
        &'a self,
        nonce: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            self.state.lock().unwrap().nonces.insert(
                nonce.nonce_hash.clone(),
                NonceState {
                    expires_at: nonce.expires_at,
                    consumed_at: None,
                    claim_id: None,
                    claim_expires_at: None,
                },
            );
            Ok(())
        })
    }

    fn consume_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let Some(nonce) = state.nonces.get_mut(nonce_hash) else {
                return Ok(false);
            };
            if nonce.consumed_at.is_some() || nonce.expires_at <= now {
                return Ok(false);
            }
            nonce.consumed_at = Some(now);
            nonce.claim_id = None;
            nonce.claim_expires_at = None;
            Ok(true)
        })
    }

    fn claim_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            Ok(Self::claim_nonce_locked(
                &mut self.state.lock().unwrap(),
                nonce_hash,
                claim_id,
                now,
            ))
        })
    }

    fn finalize_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            Ok(Self::finalize_nonce_locked(
                &mut self.state.lock().unwrap(),
                nonce_hash,
                claim_id,
                now,
            ))
        })
    }

    fn release_nonce<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let Some(nonce) = state.nonces.get_mut(nonce_hash) else {
                return Ok(false);
            };
            if nonce.consumed_at.is_some() || nonce.claim_id.as_deref() != Some(claim_id) {
                return Ok(false);
            }
            nonce.claim_id = None;
            nonce.claim_expires_at = None;
            Ok(true)
        })
    }

    fn finalize_nonce_with_notification<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            self.commit_nonce_with_side_effects(nonce_hash, claim_id, handle, None, now)
        })
    }

    fn find_response<'a>(
        &'a self,
        issuance_id: Uuid,
        token_id: Uuid,
        request_digest: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        Box::pin(async move {
            let state = self.state.lock().unwrap();
            Ok(state
                .responses
                .get(&(token_id, request_digest.to_owned()))
                .filter(|response| response.issuance_id == issuance_id && response.expires_at > now)
                .cloned())
        })
    }

    fn finalize_nonce_with_notification_and_response<'a>(
        &'a self,
        nonce_hash: &'a str,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            self.commit_nonce_with_side_effects(nonce_hash, claim_id, handle, Some(response), now)
        })
    }

    fn store_response_with_notification<'a>(
        &'a self,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let notification_key = (handle.notification_id.clone(), handle.token_id);
            let response_key = (response.token_id, response.request_digest.clone());
            if state.notifications.contains_key(&notification_key)
                || state.responses.contains_key(&response_key)
            {
                return Err(CredentialStoreError::InvalidTransition);
            }
            Self::store_notification_locked(&mut state, handle)?;
            Self::store_response_locked(&mut state, response)
        })
    }

    fn resolve_access<'a>(
        &'a self,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        Box::pin(async { Ok(None) })
    }

    fn store_deferred<'a>(
        &'a self,
        credential: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            let key = (
                credential.transaction_hash.clone(),
                credential.access.token_id,
            );
            let mut state = self.state.lock().unwrap();
            if state
                .deferred
                .insert(
                    key,
                    DeferredState {
                        credential: credential.clone(),
                        consumed_at: None,
                        claim_id: None,
                        claim_expires_at: None,
                    },
                )
                .is_some()
            {
                return Err(CredentialStoreError::InvalidTransition);
            }
            Ok(())
        })
    }

    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            self.commit_deferred_with_side_effects(
                credential,
                Some((nonce_hash, claim_id)),
                None,
                None,
                now,
            )
        })
    }

    fn store_deferred_and_finalize_nonce_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        nonce_hash: &'a str,
        claim_id: &'a str,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            self.commit_deferred_with_side_effects(
                credential,
                Some((nonce_hash, claim_id)),
                None,
                Some(response),
                now,
            )
        })
    }

    fn store_deferred_with_response<'a>(
        &'a self,
        credential: &'a DeferredCredential,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async move {
            self.commit_deferred_with_side_effects(credential, None, None, Some(response), now)
        })
    }

    fn consume_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredential>, CredentialStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let Some(deferred) = state
                .deferred
                .get_mut(&(transaction_hash.to_owned(), token_id))
            else {
                return Ok(None);
            };
            if deferred.consumed_at.is_some()
                || deferred.credential.ready_at > now
                || deferred.credential.expires_at <= now
            {
                return Ok(None);
            }
            deferred.consumed_at = Some(now);
            Ok(Some(deferred.credential.clone()))
        })
    }

    fn claim_ready_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredentialClaim>, CredentialStoreError>>
    {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let Some(deferred) = state
                .deferred
                .get_mut(&(transaction_hash.to_owned(), token_id))
            else {
                return Ok(None);
            };
            if deferred.consumed_at.is_some()
                || deferred.credential.ready_at > now
                || deferred.credential.expires_at <= now
                || deferred
                    .claim_expires_at
                    .is_some_and(|expires_at| expires_at > now)
            {
                return Ok(None);
            }
            deferred.claim_id = Some(claim_id.to_owned());
            deferred.claim_expires_at = Some(now + nonce_claim_ttl());
            Ok(Some(DeferredCredentialClaim {
                credential: deferred.credential.clone(),
                claim_id: claim_id.to_owned(),
            }))
        })
    }

    fn finalize_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let Some(deferred) = state
                .deferred
                .get_mut(&(transaction_hash.to_owned(), token_id))
            else {
                return Ok(false);
            };
            if deferred.consumed_at.is_some()
                || deferred.credential.expires_at <= now
                || deferred.claim_id.as_deref() != Some(claim_id)
            {
                return Ok(false);
            }
            deferred.consumed_at = Some(now);
            deferred.claim_id = None;
            deferred.claim_expires_at = None;
            Ok(true)
        })
    }

    fn release_deferred<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let Some(deferred) = state
                .deferred
                .get_mut(&(transaction_hash.to_owned(), token_id))
            else {
                return Ok(false);
            };
            if deferred.consumed_at.is_some() || deferred.claim_id.as_deref() != Some(claim_id) {
                return Ok(false);
            }
            deferred.claim_id = None;
            deferred.claim_expires_at = None;
            Ok(true)
        })
    }

    fn finalize_deferred_with_notification<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let Some(deferred) = state.deferred.get(&(transaction_hash.to_owned(), token_id))
            else {
                return Ok(false);
            };
            if deferred.consumed_at.is_some()
                || deferred.credential.expires_at <= now
                || deferred.claim_id.as_deref() != Some(claim_id)
            {
                return Ok(false);
            }
            Self::store_notification_locked(&mut state, handle)?;
            let deferred = state
                .deferred
                .get_mut(&(transaction_hash.to_owned(), token_id))
                .expect("deferred checked above");
            deferred.consumed_at = Some(now);
            deferred.claim_id = None;
            deferred.claim_expires_at = None;
            Ok(true)
        })
    }

    fn finalize_deferred_with_notification_and_response<'a>(
        &'a self,
        transaction_hash: &'a str,
        token_id: Uuid,
        claim_id: &'a str,
        handle: &'a NotificationHandle,
        response: &'a StoredCredentialResponse,
        now: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let Some(deferred) = state.deferred.get(&(transaction_hash.to_owned(), token_id))
            else {
                return Ok(false);
            };
            if deferred.consumed_at.is_some()
                || deferred.credential.expires_at <= now
                || deferred.claim_id.as_deref() != Some(claim_id)
            {
                return Ok(false);
            }
            let response_key = (response.token_id, response.request_digest.clone());
            if state.responses.contains_key(&response_key) {
                return Err(CredentialStoreError::InvalidTransition);
            }
            Self::store_notification_locked(&mut state, handle)?;
            Self::store_response_locked(&mut state, response)?;
            let deferred = state
                .deferred
                .get_mut(&(transaction_hash.to_owned(), token_id))
                .expect("deferred checked above");
            deferred.consumed_at = Some(now);
            deferred.claim_id = None;
            deferred.claim_expires_at = None;
            Ok(true)
        })
    }

    fn record_notification<'a>(
        &'a self,
        notification: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async move {
            let mut state = self.state.lock().unwrap();
            let key = (notification.notification_id.clone(), notification.token_id);
            let Some(stored) = state.notifications.get_mut(&key) else {
                return Ok(false);
            };
            if stored.event.is_some() || stored.handle.expires_at <= notification.occurred_at {
                return Ok(false);
            }
            stored.event = Some(notification.event.clone());
            Ok(true)
        })
    }

    fn issue_notification_handle<'a>(
        &'a self,
        handle: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(
            async move { Self::store_notification_locked(&mut self.state.lock().unwrap(), handle) },
        )
    }
}

/// A deliberately minimal adapter that leaves the optional response-aware
/// operations on [`CredentialStorePort`] at their fail-closed defaults.  The
/// production adapters implement those operations transactionally; this test
/// proves that an older adapter cannot silently report success when the
/// service attempts to use a response-aware transition.
#[derive(Clone, Copy, Default)]
struct DefaultMethodsStore;

impl CredentialStorePort for DefaultMethodsStore {
    fn upsert_access<'a>(
        &'a self,
        _: &'a str,
        _: &'a CredentialAccess,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn offer<'a>(
        &'a self,
        _: Uuid,
        _: Uuid,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialOffer>, CredentialStoreError>>
    {
        Box::pin(async { Ok(None) })
    }

    fn consume_pre_authorized_offer<'a>(
        &'a self,
        _: Uuid,
        _: &'a str,
        _: Option<&'a str>,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<
        'a,
        Result<Option<nazo_openid4vci::CredentialAuthorization>, CredentialStoreError>,
    > {
        Box::pin(async { Ok(None) })
    }

    fn issue_nonce<'a>(
        &'a self,
        _: &'a NonceRecord,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn consume_nonce<'a>(
        &'a self,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn claim_nonce<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn finalize_nonce<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn release_nonce<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn finalize_nonce_with_notification<'a>(
        &'a self,
        _: &'a str,
        _: &'a str,
        _: &'a NotificationHandle,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn find_response<'a>(
        &'a self,
        _: Uuid,
        _: Uuid,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<StoredCredentialResponse>, CredentialStoreError>>
    {
        Box::pin(async { Ok(None) })
    }

    fn resolve_access<'a>(
        &'a self,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<CredentialAccess>, CredentialStoreError>> {
        Box::pin(async { Ok(None) })
    }

    fn store_deferred<'a>(
        &'a self,
        _: &'a DeferredCredential,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn store_deferred_and_finalize_nonce<'a>(
        &'a self,
        _: &'a DeferredCredential,
        _: &'a str,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
    }

    fn consume_ready_deferred<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredential>, CredentialStoreError>> {
        Box::pin(async { Ok(None) })
    }

    fn claim_ready_deferred<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<Option<DeferredCredentialClaim>, CredentialStoreError>>
    {
        Box::pin(async { Ok(None) })
    }

    fn finalize_deferred<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn release_deferred<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn finalize_deferred_with_notification<'a>(
        &'a self,
        _: &'a str,
        _: Uuid,
        _: &'a str,
        _: &'a NotificationHandle,
        _: DateTime<Utc>,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn record_notification<'a>(
        &'a self,
        _: &'a IssuanceNotification,
    ) -> CredentialStoreFuture<'a, Result<bool, CredentialStoreError>> {
        Box::pin(async { Ok(false) })
    }

    fn issue_notification_handle<'a>(
        &'a self,
        _: &'a NotificationHandle,
    ) -> CredentialStoreFuture<'a, Result<(), CredentialStoreError>> {
        Box::pin(async { Ok(()) })
    }
}

#[test]
fn response_aware_store_defaults_fail_closed_for_legacy_adapters() {
    let now = Utc::now();
    let store = DefaultMethodsStore;
    let deferred = deferred_fixture(now);
    let handle = NotificationHandle {
        notification_id: "notification-default".to_owned(),
        token_id: deferred.access.token_id,
        expires_at: now + Duration::minutes(5),
    };
    let response = response_fixture(Uuid::now_v7(), deferred.access.token_id, now);

    assert_eq!(
        block_on(store.finalize_nonce_with_notification_and_response(
            "nonce", "claim", &handle, &response, now,
        )),
        Err(CredentialStoreError::Unavailable)
    );
    assert_eq!(
        block_on(store.store_response_with_notification(&handle, &response, now)),
        Err(CredentialStoreError::Unavailable)
    );
    assert_eq!(
        block_on(store.store_deferred_and_finalize_nonce_with_response(
            &deferred, "nonce", "claim", &response, now,
        )),
        Err(CredentialStoreError::Unavailable)
    );
    assert_eq!(
        block_on(store.store_deferred_with_response(&deferred, &response, now)),
        Err(CredentialStoreError::Unavailable)
    );
    assert_eq!(
        block_on(store.finalize_deferred_with_notification_and_response(
            &deferred.transaction_hash,
            deferred.access.token_id,
            "claim",
            &handle,
            &response,
            now,
        )),
        Err(CredentialStoreError::Unavailable)
    );
}

fn block_on<T>(future: impl Future<Output = T>) -> T {
    tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("test runtime")
        .block_on(future)
}

fn deferred_fixture(now: DateTime<Utc>) -> DeferredCredential {
    DeferredCredential {
        id: Uuid::now_v7(),
        transaction_hash: "tx-hash".to_owned(),
        access: CredentialAccess {
            token_id: Uuid::now_v7(),
            tenant_id: Uuid::now_v7(),
            subject_id: Uuid::now_v7(),
            client_id: "wallet".to_owned(),
            configuration_ids: vec!["pid".to_owned()],
            credential_identifiers: vec![CredentialIdentifier("pid-1".to_owned())],
            dpop_jkt: None,
            expires_at: now + Duration::hours(1),
        },
        configuration_id: "pid".to_owned(),
        format: CredentialFormat::SdJwtVc,
        holder_bindings: vec![json!({"jwk":{"kid":"holder"}})],
        payload_ciphertext: br#"{"given_name":"Ada"}"#.to_vec(),
        ready_at: now + Duration::minutes(1),
        expires_at: now + Duration::hours(1),
    }
}

fn response_fixture(
    issuance_id: Uuid,
    token_id: Uuid,
    now: DateTime<Utc>,
) -> StoredCredentialResponse {
    StoredCredentialResponse {
        issuance_id,
        token_id,
        request_digest: "request-digest".to_owned(),
        body: br#"{"credentials":[]}"#.to_vec(),
        encoding: CredentialResponseEncoding::Json,
        status: 200,
        dpop_nonce: None,
        expires_at: now + Duration::minutes(10),
    }
}

#[test]
fn nonce_claim_is_single_owner_until_lease_timeout_then_replay_is_rejected() {
    let now = DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
        .unwrap()
        .with_timezone(&Utc);
    let store = TransitionStore::default();
    let hash = "nonce-hash";
    block_on(store.issue_nonce(&NonceRecord {
        nonce_hash: hash.to_owned(),
        expires_at: now + Duration::hours(1),
    }))
    .unwrap();

    assert!(block_on(store.claim_nonce(hash, "claim-a", now)).unwrap());
    assert!(!block_on(store.claim_nonce(hash, "claim-b", now + Duration::minutes(1))).unwrap());
    assert!(block_on(store.claim_nonce(hash, "claim-b", now + nonce_claim_ttl())).unwrap());
    assert!(!block_on(store.finalize_nonce(hash, "claim-a", now + nonce_claim_ttl())).unwrap());
    assert!(block_on(store.finalize_nonce(hash, "claim-b", now + nonce_claim_ttl())).unwrap());
    assert!(!block_on(store.claim_nonce(hash, "claim-c", now + nonce_claim_ttl())).unwrap());
    assert!(store.nonce(hash).consumed_at.is_some());
}

#[test]
fn nonce_notification_commit_is_atomic_and_rejects_wrong_claim_without_side_effects() {
    let now = Utc::now();
    let store = TransitionStore::default();
    let hash = "nonce-hash";
    let token_id = Uuid::now_v7();
    let handle = NotificationHandle {
        notification_id: "notification-1".to_owned(),
        token_id,
        expires_at: now + Duration::minutes(10),
    };
    block_on(store.issue_nonce(&NonceRecord {
        nonce_hash: hash.to_owned(),
        expires_at: now + Duration::hours(1),
    }))
    .unwrap();
    assert!(block_on(store.claim_nonce(hash, "claim-a", now)).unwrap());

    assert!(
        !block_on(store.finalize_nonce_with_notification(hash, "wrong-claim", &handle, now,))
            .unwrap()
    );
    assert_eq!(store.notification_count(), 0);
    assert!(store.nonce(hash).consumed_at.is_none());

    assert!(
        block_on(store.finalize_nonce_with_notification(hash, "claim-a", &handle, now)).unwrap()
    );
    assert_eq!(store.notification_count(), 1);
    assert!(
        !block_on(store.finalize_nonce_with_notification(hash, "claim-a", &handle, now)).unwrap()
    );
}

#[test]
fn deferred_claim_is_ready_single_owner_reclaimable_and_finalized_once() {
    let now = Utc::now();
    let store = TransitionStore::default();
    let deferred = deferred_fixture(now);
    let tx_hash = deferred.transaction_hash.clone();
    let token_id = deferred.access.token_id;
    block_on(store.store_deferred(&deferred)).unwrap();

    assert!(
        block_on(store.claim_ready_deferred(&tx_hash, token_id, "claim-a", now))
            .unwrap()
            .is_none()
    );
    let ready_at = deferred.ready_at;
    assert!(
        block_on(store.claim_ready_deferred(&tx_hash, token_id, "claim-a", ready_at))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.claim_ready_deferred(
            &tx_hash,
            token_id,
            "claim-b",
            ready_at + Duration::minutes(1),
        ))
        .unwrap()
        .is_none()
    );
    assert!(
        block_on(store.claim_ready_deferred(
            &tx_hash,
            token_id,
            "claim-b",
            ready_at + nonce_claim_ttl(),
        ))
        .unwrap()
        .is_some()
    );
    assert!(
        !block_on(store.finalize_deferred(
            &tx_hash,
            token_id,
            "claim-a",
            ready_at + nonce_claim_ttl(),
        ))
        .unwrap()
    );
    assert!(
        block_on(store.finalize_deferred(
            &tx_hash,
            token_id,
            "claim-b",
            ready_at + nonce_claim_ttl(),
        ))
        .unwrap()
    );
    assert!(
        store
            .deferred(&tx_hash, token_id)
            .unwrap()
            .consumed_at
            .is_some()
    );
}

#[test]
fn deferred_nonce_commit_rolls_back_all_state_when_claim_is_invalid() {
    let now = Utc::now();
    let store = TransitionStore::default();
    let deferred = deferred_fixture(now);
    let hash = "nonce-hash";
    block_on(store.issue_nonce(&NonceRecord {
        nonce_hash: hash.to_owned(),
        expires_at: now + Duration::hours(1),
    }))
    .unwrap();
    assert!(block_on(store.claim_nonce(hash, "claim-a", now)).unwrap());

    assert_eq!(
        block_on(store.store_deferred_and_finalize_nonce(&deferred, hash, "wrong-claim", now,)),
        Err(CredentialStoreError::InvalidTransition)
    );
    assert!(
        store
            .deferred(&deferred.transaction_hash, deferred.access.token_id)
            .is_none()
    );
    assert!(store.nonce(hash).consumed_at.is_none());

    block_on(store.store_deferred_and_finalize_nonce(&deferred, hash, "claim-a", now)).unwrap();
    assert!(
        store
            .deferred(&deferred.transaction_hash, deferred.access.token_id)
            .is_some()
    );
    assert!(store.nonce(hash).consumed_at.is_some());
}

#[test]
fn response_lookup_is_bound_to_issuance_identity_and_expiry() {
    let now = Utc::now();
    let store = TransitionStore::default();
    let issuance_id = Uuid::now_v7();
    let token_id = Uuid::now_v7();
    let response = response_fixture(issuance_id, token_id, now);
    let handle = NotificationHandle {
        notification_id: "notification-1".to_owned(),
        token_id,
        expires_at: now + Duration::minutes(10),
    };
    block_on(store.issue_nonce(&NonceRecord {
        nonce_hash: "nonce".to_owned(),
        expires_at: now + Duration::hours(1),
    }))
    .unwrap();
    assert!(block_on(store.claim_nonce("nonce", "claim", now)).unwrap());
    assert!(
        block_on(store.finalize_nonce_with_notification_and_response(
            "nonce", "claim", &handle, &response, now,
        ))
        .unwrap()
    );
    assert_eq!(store.response_count(), 1);
    assert!(
        block_on(store.find_response(issuance_id, token_id, "request-digest", now,))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.find_response(Uuid::now_v7(), token_id, "request-digest", now,))
            .unwrap()
            .is_none()
    );
    assert!(
        block_on(store.find_response(issuance_id, Uuid::now_v7(), "request-digest", now,))
            .unwrap()
            .is_none()
    );
    assert!(
        block_on(store.find_response(issuance_id, token_id, "different-request", now,))
            .unwrap()
            .is_none()
    );
    assert!(
        block_on(store.find_response(
            issuance_id,
            token_id,
            "request-digest",
            now + Duration::minutes(11),
        ))
        .unwrap()
        .is_none()
    );
}

#[test]
fn response_commit_rejects_duplicate_notification_atomically_and_can_retry() {
    let now = Utc::now();
    let store = TransitionStore::default();
    let token_id = Uuid::now_v7();
    let handle = NotificationHandle {
        notification_id: "notification-duplicate".to_owned(),
        token_id,
        expires_at: now + Duration::minutes(10),
    };
    let first = response_fixture(Uuid::now_v7(), token_id, now);
    block_on(store.issue_notification_handle(&handle)).unwrap();
    let mut second = response_fixture(Uuid::now_v7(), token_id, now);
    second.request_digest = "request-digest-2".to_owned();

    assert_eq!(
        block_on(store.store_response_with_notification(&handle, &second, now)),
        Err(CredentialStoreError::InvalidTransition)
    );
    assert_eq!(store.response_count(), 0);

    let retry_handle = NotificationHandle {
        notification_id: "notification-retry".to_owned(),
        ..handle
    };
    block_on(store.store_response_with_notification(&retry_handle, &first, now)).unwrap();
    assert_eq!(store.response_count(), 1);
    let second_retry_handle = NotificationHandle {
        notification_id: "notification-retry-2".to_owned(),
        ..retry_handle
    };
    block_on(store.store_response_with_notification(&second_retry_handle, &second, now)).unwrap();
    assert_eq!(store.response_count(), 2);
}

#[test]
fn response_identity_conflict_is_keyed_by_token_and_digest_across_issuances() {
    let now = Utc::now();
    let store = TransitionStore::default();
    let token_id = Uuid::now_v7();
    let first = response_fixture(Uuid::now_v7(), token_id, now);
    let first_handle = NotificationHandle {
        notification_id: "notification-first".to_owned(),
        token_id,
        expires_at: now + Duration::minutes(10),
    };
    block_on(store.store_response_with_notification(&first_handle, &first, now)).unwrap();

    let second = response_fixture(Uuid::now_v7(), token_id, now);
    let second_handle = NotificationHandle {
        notification_id: "notification-second".to_owned(),
        token_id,
        expires_at: now + Duration::minutes(10),
    };
    assert_eq!(
        block_on(store.store_response_with_notification(&second_handle, &second, now,)),
        Err(CredentialStoreError::InvalidTransition)
    );
    assert_eq!(store.response_count(), 1);
    assert!(
        block_on(store.find_response(first.issuance_id, token_id, &first.request_digest, now,))
            .unwrap()
            .is_some()
    );
    assert!(
        block_on(store.find_response(second.issuance_id, token_id, &second.request_digest, now,))
            .unwrap()
            .is_none()
    );
}

#[test]
fn notification_event_is_single_use_and_expires_with_the_handle() {
    let now = Utc::now();
    let store = TransitionStore::default();
    let token_id = Uuid::now_v7();
    let handle = NotificationHandle {
        notification_id: "notification-1".to_owned(),
        token_id,
        expires_at: now + Duration::minutes(1),
    };
    block_on(store.issue_notification_handle(&handle)).unwrap();
    let notification = IssuanceNotification {
        notification_id: handle.notification_id.clone(),
        token_id,
        event: NotificationEvent::CredentialAccepted,
        description: None,
        occurred_at: now,
    };
    assert!(block_on(store.record_notification(&notification)).unwrap());
    assert!(!block_on(store.record_notification(&notification)).unwrap());
    assert!(
        !block_on(store.record_notification(&IssuanceNotification {
            occurred_at: now + Duration::minutes(2),
            ..notification
        }))
        .unwrap()
    );
}

#[test]
fn nonce_claim_is_linearizable_under_concurrent_requests() {
    let now = Utc::now();
    let store = TransitionStore::default();
    block_on(store.issue_nonce(&NonceRecord {
        nonce_hash: "nonce".to_owned(),
        expires_at: now + Duration::hours(1),
    }))
    .unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let (first, second) = thread::scope(|scope| {
        let first_store = store.clone();
        let first_barrier = barrier.clone();
        let first = scope.spawn(move || {
            first_barrier.wait();
            block_on(first_store.claim_nonce("nonce", "claim-a", now)).unwrap()
        });
        let second_store = store.clone();
        let second_barrier = barrier.clone();
        let second = scope.spawn(move || {
            second_barrier.wait();
            block_on(second_store.claim_nonce("nonce", "claim-b", now)).unwrap()
        });
        barrier.wait();
        (
            first.join().expect("first claim worker"),
            second.join().expect("second claim worker"),
        )
    });
    assert_ne!(first, second);
}
