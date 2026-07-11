# WebAuthn Passkeys

## Scope

The local identity profile supports WebAuthn/passkey registration and
email-first passkey login. Passkeys create normal server-side sessions and do
not bypass OAuth/OIDC authorization, consent, token, or tenant checks.

## Configuration

- `PASSKEY_RP_ID`: bare relying-party host name, without scheme, port, or path. Defaults to the host of `PASSKEY_ORIGIN`.
- `PASSKEY_RP_NAME`: display name shown by the browser during the WebAuthn ceremony.
- `PASSKEY_ORIGIN`: exact browser origin expected in `clientDataJSON.origin`. Defaults to the issuer derived from `PUBLIC_BASE_URL`.
- `PASSKEY_REQUIRE_USER_VERIFICATION`: requires authenticator user verification such as biometrics or PIN.
- `PASSKEY_REQUIRE_USER_HANDLE`: requires assertions to include the expected user handle for username-first login.
- `PASSKEY_STRICT_BASE64`: requires WebAuthn binary fields to use spec-compliant base64url without padding.

Production deployments keep user verification, user handle, and strict base64
enabled.

## Endpoints

User passkey management:

- `POST /auth/me/passkeys/registration/begin`
- `POST /auth/me/passkeys/registration/finish`
- `GET /auth/me/passkeys`
- `DELETE /auth/me/passkeys/{passkey_id}`

Passkey login:

- `POST /auth/passkey/begin`
- `POST /auth/passkey/finish`

Registration and deletion require the existing HTTPOnly session cookie plus CSRF validation. Login uses an email-first flow so the server can scope allowed credentials to one active tenant-bound user.

## Security Model

WebAuthn ceremonies use the `passkey-auth` verifier. The server verifies challenge freshness, exact origin, RP ID hash, authenticator signature, user verification policy, user-handle binding, and authenticator counter replay protection.

Ceremony state is stored only in Valkey with a five-minute TTL and is consumed with `GETDEL` at finish time. Persisted credentials are bound to `(tenant_id, user_id)` and credential ID uniqueness is enforced per tenant.

Successful passkey login creates the normal HTTPOnly server-side session with
`amr=["passkey"]`.
