# Refresh Token Rotation

## Scope

Non-FAPI compatibility profiles use the refresh-token behavior below. FAPI2
Security deployments do not use routine refresh-token rotation by default.
Refresh grants still require confidential client authentication and the
configured DPoP or mTLS proof. Newly issued access tokens remain
sender-constrained.

## State Machine

| State | Meaning | Accepted action |
| --- | --- | --- |
| Active | Refresh token is not expired and `revoked_at` is null. | A valid refresh request rotates it to a new active successor. |
| Rotated | Refresh token has `revoked_at` set and exactly one active successor whose `rotated_from_id` points to it. | A retry with the old token is accepted only during the lost-response retry window. |
| Reused | A revoked token is presented outside the retry window, has no active successor, has multiple successors, or the family already has `reuse_detected_at`. | Mark the token family as reused and revoke any remaining active family tokens. |
| Expired | Token expiry is in the past. | Reject with `invalid_grant`; do not issue a successor. |

## Lost-Response Retry

If a client successfully rotates a refresh token but loses the HTTP response before storing the successor, it may retry the same old refresh token briefly. The server accepts this only when all conditions are true:

- the old token belongs to the authenticated client
- the old token is within `LOST_REFRESH_TOKEN_RETRY_SECONDS` after `revoked_at`
- the token family has no recorded reuse
- exactly one non-expired, non-revoked successor exists for the old token
- the sender constraint on the old token still validates

The retry continues from the active successor and rotates again. Any ambiguous or late reuse is treated as replay, not compatibility recovery.

## Sender Constraints

DPoP-bound refresh tokens require a valid DPoP proof for refresh. mTLS-bound refresh tokens require a verified forwarded certificate thumbprint from a trusted proxy and constant-time match against the stored certificate thumbprint.

## Tests

Unit coverage:

- the lost-response retry window boundary
- rejection of `revoked_at` timestamps later than the current clock
- DPoP-bound refresh proof requirements
- mTLS-bound refresh proof requirements
- refresh issuance requiring both `offline_access` and the client `refresh_token` grant

Deployments that advertise lost-response recovery as a production guarantee
need database integration coverage for full Active -> Rotated -> Reused family
transitions.
