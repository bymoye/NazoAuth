use super::*;
use crate::http::scim::auth::ScimCredential;
use chrono::{Duration, Utc};
use uuid::Uuid;

fn cursor_key() -> ScimCursorKey {
    ScimCursorKey::from_client_secret_pepper("cursor-test-pepper-32-bytes-minimum-value")
        .expect("cursor test key should derive")
}

fn database_credential() -> ScimCredential {
    ScimCredential {
        token_id: Some(Uuid::from_u128(0x11111111111111111111111111111111)),
        tenant_id: Uuid::from_u128(0x22222222222222222222222222222222),
        scopes: vec!["scim:read".to_owned()],
        source: "database",
    }
}

#[test]
fn scim_cursor_round_trip_is_opaque_url_safe_and_randomized() {
    let key = cursor_key();
    let credential = database_credential();
    let filter = Some("userName eq \"alice@example.test\"");
    let now = Utc::now();
    let last_created_at = now - Duration::seconds(30);
    let last_id = Uuid::from_u128(0x33333333333333333333333333333333);
    let context = ScimCursorContext {
        credential: &credential,
        filter,
        count: 25,
        last_created_at,
        last_id,
    };

    let first = encode_scim_cursor(&key, &context, now).expect("cursor should encode");
    let second = encode_scim_cursor(&key, &context, now).expect("cursor should encode");

    assert_ne!(first, second);
    assert!(
        first
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    );
    assert!(!first.contains('='));
    assert!(!first.contains("alice@example.test"));
    assert!(!first.contains(&credential.tenant_id.to_string()));
    assert!(!first.contains(&credential.token_id.expect("token id").to_string()));
    assert!(!first.contains(&last_id.to_string()));
    assert_eq!(
        decode_scim_cursor(&key, &first, &credential, filter, 25, now,),
        Ok(ScimCursorPosition {
            last_created_at,
            last_id,
        })
    );
}

fn encoded_cursor(
    key: &ScimCursorKey,
    credential: &ScimCredential,
    now: chrono::DateTime<Utc>,
) -> String {
    encode_scim_cursor(
        key,
        &ScimCursorContext {
            credential,
            filter: Some("userName eq \"alice@example.test\""),
            count: 25,
            last_created_at: now - Duration::seconds(30),
            last_id: Uuid::from_u128(0x33333333333333333333333333333333),
        },
        now,
    )
    .expect("cursor should encode")
}

#[test]
fn scim_cursor_rejects_count_filter_actor_and_tenant_changes() {
    let key = cursor_key();
    let credential = database_credential();
    let now = Utc::now();
    let encoded = encoded_cursor(&key, &credential, now);

    assert_eq!(
        decode_scim_cursor(
            &key,
            &encoded,
            &credential,
            Some("userName eq \"alice@example.test\""),
            26,
            now,
        ),
        Err(ScimCursorError::InvalidCount)
    );
    assert_eq!(
        decode_scim_cursor(&key, &encoded, &credential, None, 25, now),
        Err(ScimCursorError::Invalid)
    );

    let mut other_actor = credential.clone();
    other_actor.token_id = Some(Uuid::from_u128(0x44444444444444444444444444444444));
    assert_eq!(
        decode_scim_cursor(
            &key,
            &encoded,
            &other_actor,
            Some("userName eq \"alice@example.test\""),
            25,
            now,
        ),
        Err(ScimCursorError::Invalid)
    );

    let mut other_tenant = credential.clone();
    other_tenant.tenant_id = Uuid::from_u128(0x55555555555555555555555555555555);
    assert_eq!(
        decode_scim_cursor(
            &key,
            &encoded,
            &other_tenant,
            Some("userName eq \"alice@example.test\""),
            25,
            now,
        ),
        Err(ScimCursorError::Invalid)
    );
}

#[test]
fn scim_cursor_rejects_expired_and_future_issued_payloads() {
    let key = cursor_key();
    let credential = database_credential();
    let now = Utc::now();
    let encoded = encoded_cursor(&key, &credential, now);

    assert_eq!(
        decode_scim_cursor(
            &key,
            &encoded,
            &credential,
            Some("userName eq \"alice@example.test\""),
            25,
            now + Duration::seconds(SCIM_CURSOR_TIMEOUT_SECONDS),
        ),
        Err(ScimCursorError::Expired)
    );

    let future = encoded_cursor(&key, &credential, now + Duration::seconds(61));
    assert_eq!(
        decode_scim_cursor(
            &key,
            &future,
            &credential,
            Some("userName eq \"alice@example.test\""),
            25,
            now,
        ),
        Err(ScimCursorError::Invalid)
    );
}

#[test]
fn scim_cursor_rejects_tampering_padding_truncation_and_oversize_input() {
    let key = cursor_key();
    let credential = database_credential();
    let now = Utc::now();
    let encoded = encoded_cursor(&key, &credential, now);
    let mut tampered = encoded.clone().into_bytes();
    let last = tampered.last_mut().expect("cursor should not be empty");
    *last = if *last == b'A' { b'B' } else { b'A' };
    let tampered = String::from_utf8(tampered).expect("cursor should remain ASCII");

    for invalid in [
        tampered,
        format!("{encoded}="),
        encoded[..8].to_owned(),
        "A".repeat(SCIM_CURSOR_MAX_ENCODED_LEN + 1),
    ] {
        assert_eq!(
            decode_scim_cursor(
                &key,
                &invalid,
                &credential,
                Some("userName eq \"alice@example.test\""),
                25,
                now,
            ),
            Err(ScimCursorError::Invalid)
        );
    }
}

#[test]
fn scim_cursor_rejects_authenticated_unknown_version_sort_and_lifetime() {
    let key = cursor_key();
    let credential = database_credential();
    let now = Utc::now();
    let base = ScimCursorPayload {
        v: SCIM_CURSOR_VERSION,
        tenant_id: credential.tenant_id,
        actor: credential_actor(&credential),
        filter: None,
        count: 25,
        sort: SCIM_CURSOR_SORT.to_owned(),
        last_created_at: now - Duration::seconds(30),
        last_id: Uuid::from_u128(0x33333333333333333333333333333333),
        issued_at: now.timestamp(),
        expires_at: now.timestamp() + SCIM_CURSOR_TIMEOUT_SECONDS,
    };

    for invalid in [
        ScimCursorPayload {
            v: 2,
            ..base.clone()
        },
        ScimCursorPayload {
            sort: "created_at".to_owned(),
            ..base.clone()
        },
        ScimCursorPayload {
            expires_at: base.issued_at + SCIM_CURSOR_TIMEOUT_SECONDS + 1,
            ..base.clone()
        },
        ScimCursorPayload {
            expires_at: base.issued_at,
            ..base.clone()
        },
    ] {
        let encoded = encrypt_scim_cursor_payload(&key, &invalid)
            .expect("authenticated invalid cursor fixture should encode");
        assert_eq!(
            decode_scim_cursor(&key, &encoded, &credential, None, 25, now),
            Err(ScimCursorError::Invalid)
        );
    }
}
