# Composable Capability Policy

## Why capabilities are not one exclusive profile

NazoAuth separates three independent questions:

1. **Server support**: is the endpoint, protocol handler, and operational
   dependency available?
2. **Client authority**: may this client use the capability?
3. **Assurance and message protection**: which additional security invariants
   must this client satisfy?

Server support is therefore not equivalent to client authorization. Stable,
non-conflicting handlers can be active together while client grant allowlists
and `security_policy` continue to deny use by default.

`AUTHORIZATION_SERVER_PROFILE` remains a compatibility preset for clients
created before versioned per-client policy existed. New clients receive an
explicit policy and do not depend on that global preset.

## New-install server defaults

The following stable runtime modules are enabled on a new database:

| Module | Why server support is safe to enable | Client-side authority |
| --- | --- | --- |
| Request Objects / JAR | Signed input is validated; unsigned JAR remains forbidden | Optional request, or `require_signed_authorization_request` |
| JARM | Adds a protected response form without removing baseline responses | `require_signed_authorization_response` or explicit `response_mode=jwt` |
| Device Authorization Grant | Endpoint availability does not grant a client the flow | Device grant allowlist **and** `allow_cross_device_flows=true` |
| CIBA poll/ping | Poll and ping coexist; push remains unsupported | CIBA grant/metadata **and** `allow_cross_device_flows=true` |
| Token Exchange | The implementation is a bounded local-token profile | Client grant allowlist and existing target/scope checks |
| JWT Bearer Grant | The implemented profile remains client-bound | Client grant allowlist and client authentication |
| SCIM | Server role can coexist with OAuth/OIDC roles | SCIM bearer authority and scope checks |
| Front-Channel Logout | Endpoint support does not register an RP logout URI | Registered client logout metadata |
| Session Management | The iframe can coexist with logout and OIDC | `session_management=true` |

The following modules are enabled only when their real prerequisite exists:

| Module | Prerequisite |
| --- | --- |
| Dynamic Client Registration | A non-empty `DYNAMIC_CLIENT_REGISTRATION_INITIAL_ACCESS_TOKEN` |
| Rich Authorization Requests | Explicit RAR deployment configuration |
| SCIM Security Events | Receiver/event configuration |
| OpenID4VCI / OpenID4VP | Complete role, credential, and trust configuration |
| Native SSO | Explicit draft-profile opt-in; Token Exchange is enabled as a dependency |
| FAPI HTTP Signatures | Explicit experimental opt-in |

Draft, experimental, remote-trust, and debug behavior remains default-off.
Implicit, hybrid, Resource Owner Password Credentials, unsigned Request
Objects, query bearer tokens, and CIBA push are not optional capabilities and
cannot be enabled.

## Versioned per-client policy

Admin-created clients receive this default policy:

```json
{
  "version": 1,
  "assurance": "baseline",
  "require_signed_authorization_request": false,
  "require_signed_authorization_response": false,
  "require_signed_introspection_response": false,
  "session_management": false,
  "allow_cross_device_flows": false
}
```

RFC 7591 registration also materializes the baseline policy and cannot
self-assign FAPI, session, or cross-device authority. An administrator may
compose compatible controls, for example:

```json
{
  "version": 1,
  "assurance": "fapi2",
  "require_signed_authorization_request": true,
  "require_signed_authorization_response": true,
  "require_signed_introspection_response": true,
  "session_management": true,
  "allow_cross_device_flows": true
}
```

These fields are independent. FAPI2 assurance enforces confidential client
type, strong client authentication, PAR, S256 PKCE, sender-constrained tokens,
and the FAPI authorization-code lifetime. It does not prevent JAR, JARM, signed
introspection, CIBA, Device Grant, or Session Management from being selected at
the same time.

Registration validation fails closed when an explicit policy cannot be
satisfied. For example, FAPI2 without DPoP or mTLS is rejected, and mandatory
signed authorization requests require a registered signing-key source.
Unknown policy versions and fields are rejected.

## Upgrade behavior

The runtime default-policy version and client policy are persisted.

- On a **new database**, the composable defaults above are seeded.
- On an **existing database**, every inherited runtime-module state is
  atomically materialized as an explicit enabled/disabled row using the
  current composable defaults. This gives the database one authoritative
  policy source after the upgrade.
- Existing clients with no stored `security_policy` retain the old
  `AUTHORIZATION_SERVER_PROFILE` behavior as a compatibility fallback.
- Any newly created client receives an explicit version-1 baseline policy.

After migration, runtime module administration is authoritative. The removed
legacy stable-module `ENABLE_*` flags are not accepted by the configuration
loader and are not a second competing source of truth.

## Discovery semantics

Discovery publishes the union of currently active server capabilities.
Discovery does not claim that every registered client may use every published
feature. The authenticated request is still checked against the client's grant
allowlist, metadata, sender constraints, and `security_policy`.
