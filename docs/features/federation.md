# External Identity Federation

## Scope

External federation belongs to the identity-platform surface. It is separate
from OAuth/OIDC authorization-server conformance.

Supported federation modes:

- configuration-driven external provider registry
- multiple modular external OIDC provider instances
- OAuth2 social provider adapters for QQ, WeChat, and custom JSON userinfo providers
- one trusted SAML gateway integration
- default-tenant external identity links
- normal HTTPOnly server-side sessions after successful federation login

## Provider Registry

Third-party login providers are loaded from `FEDERATION_PROVIDER_CONFIGS`, a
JSON array of provider definitions. Each provider has its own `provider_id`,
`enabled` flag, display name, adapter type, client credentials, redirect URI,
scope, provider endpoints, claim mapping, optional icon, and display order.

Enabled providers are exposed to the login UI through:

- `GET /auth/federation/providers`

Provider-specific login routes are:

- `GET /auth/federation/{provider_id}/start`
- `GET /auth/federation/{provider_id}/callback`

Disabled providers are not returned by the public provider list and cannot be
started through the dynamic route. Admin onboarding can inspect non-secret
provider state through:

- `GET /admin/federation/providers`

The admin view reports callback URLs and whether secret-backed fields are
configured, but it does not return client secrets, provider access tokens, JWKS
contents, or raw assertions.

## External OIDC Login

OIDC providers can be configured as registry entries with `adapter_type:
"oidc"` inside `FEDERATION_PROVIDER_CONFIGS`. Each provider owns its callback
URL through its `provider_id`.

Endpoints:

- `GET /auth/federation/{provider_id}/start`
- `GET /auth/federation/{provider_id}/callback`

The flow uses authorization code, PKCE S256, nonce, short-lived Valkey state,
token endpoint exchange, JWKS lookup, and ID Token verification. The server
checks issuer, audience, expiry, nonce, `kid`, and signature. The ID Token must
contain an email claim and `email_verified=true`; absent or false verification
claims are rejected before account lookup, linking, or provisioning.

## OAuth2 Social Login

OAuth2 social providers use `adapter_type: "oauth2_social"` and a
provider-specific adapter. Built-in presets exist for:

- `provider_kind: "qq"`
- `provider_kind: "wechat"`

Custom providers can supply explicit authorization, token, and userinfo
endpoints plus claim names. QQ and WeChat are not treated as OIDC providers and
do not use ID Token validation. Their third-party access tokens are used only
inside the adapter to fetch external identity claims and are not persisted as
NazoAuth access tokens, session credentials, or long-lived local privileges.

Social adapters normalize a provider subject from `openid`, `unionid`, or a
configured subject claim. A verified email claim may be used as a contact and
provisioning attribute, but email is not the external identity root. Providers
without email can only authenticate an already linked external identity; they do
not auto-provision or auto-link local accounts.

This is not an OpenID Federation trust-chain implementation. The service does
not expose `/.well-known/openid-federation` or implement Federation entity
statements, trust anchors, metadata policy, trust marks, or federation
fetch/list/resolve endpoints.

## SAML Gateway Federation

The application does not parse raw SAML XML and does not accept unsigned
browser-posted assertions. SAML support runs through a trusted gateway. The
gateway handles XML parsing, XMLDSig validation, IdP metadata checks, and replay
protection before forwarding a compact signed assertion to this service.

Configuration:

- `FEDERATION_SAML_GATEWAY_ENABLED`
- `FEDERATION_SAML_GATEWAY_ISSUER`
- `FEDERATION_SAML_GATEWAY_AUDIENCE`
- `FEDERATION_SAML_GATEWAY_SECRET`

Endpoint:

- `POST /auth/federation/saml/acs`

The gateway assertion is HMAC-SHA256 signed over issuer, audience, subject,
normalized email, `iat`, and `exp`. The application enforces issuer, audience,
timestamp bounds, a five-minute maximum assertion lifetime, normalized email,
and constant-time signature comparison.

## Identity Linking

External identities are stored in `external_identity_links` and bound to the
default tenant. The unique key is `(tenant_id, provider_type, provider_id,
subject)`.

Resolution order:

- an existing active link selects the linked user
- without an existing link, a same-email local user is not auto-linked
- otherwise a local user is provisioned with a random unusable password hash and
  `email_verified=true`

Successful federation login creates the normal HTTPOnly server-side session.
The session `amr` contains the federation method and `federated`.

Current users can inspect and remove their own external identity links through:

- `GET /auth/me/federation/links`
- `DELETE /auth/me/federation/links/{link_id}`

The link list omits raw provider claims. Unlink operations are scoped by the
current session user and emit `external_identity_unlinked` audit events.

Local session state remains the NazoAuth fact source. External provider logout
failures do not mark remote logout as complete; local `/auth/logout` and OIDC
OP logout clear the local session independently of upstream provider state.
