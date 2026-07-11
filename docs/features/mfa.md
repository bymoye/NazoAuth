# MFA and Step-Up Authentication

## Scope

Local account MFA supports TOTP, one-time backup codes, remembered MFA devices,
and session step-up state. It is an identity-platform feature, not an OAuth/OIDC
profile requirement.

## Runtime Behavior

- `POST /auth/me/mfa/totp/begin` creates or refreshes an unconfirmed TOTP secret for the fully authenticated current user.
- `POST /auth/me/mfa/totp/confirm` verifies the first TOTP code, marks the TOTP credential confirmed, enables `users.mfa_enabled`, steps up the current session with `otp` and `mfa`, and returns fresh backup codes once.
- `POST /auth/mfa/verify` completes a pending MFA login challenge after password authentication. It accepts a current TOTP code or one unused backup code.
- `POST /auth/me/mfa/backup-codes/regenerate` requires a valid MFA code and replaces all backup codes.
- `POST /auth/me/mfa/disable` requires a valid MFA code, removes TOTP credentials, backup codes, remembered devices, and disables MFA for the user.

## Security Properties

- Password authentication for an MFA-enabled user creates a pending MFA session, not a fully authenticated session.
- `current_session` rejects pending MFA sessions. Authorization and profile-management endpoints therefore do not treat password-only MFA sessions as logged in.
- `/auth/me` returns `mfa_required: true` for pending MFA sessions so a frontend can continue the challenge without losing the HTTPOnly session cookie.
- TOTP uses HMAC-SHA1, six digits, 30-second steps, and a one-step clock skew window.
- Confirmed TOTP credentials track the last accepted time step and reject replay of the same or older step.
- Backup codes are generated as high-entropy display codes, normalized before verification, Argon2id-hashed at rest, and consumed once.
- Remembered MFA devices use an HTTPOnly opaque 256-bit cookie. Only a BLAKE3 hash is stored server-side, bound to the user, tenant, expiry time, and user-agent hash.
- Remembered devices satisfy the local product MFA policy but are recorded in session `amr` as `remembered_mfa`, not as a fresh OTP.

## Persistence

MFA state is stored in migration `20260607000500_totp_mfa_step_up`:

- `user_totp_credentials`: one TOTP credential per user and tenant, including confirmation state and replay step.
- `user_mfa_backup_codes`: Argon2id hashes for one-time recovery codes.
- `user_mfa_remembered_devices`: hashed remembered-device tokens with expiry and last-use metadata.

## Boundaries

WebAuthn/passkeys and external OIDC/SAML federation are separate login methods.
They do not satisfy TOTP challenge flows. SCIM provisioning is lifecycle
management; it does not satisfy local MFA challenges.
