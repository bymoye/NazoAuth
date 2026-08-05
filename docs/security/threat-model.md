# Threat Model

## Scope

The threat model covers the current authorization-server boundary. Update it
in the same change that adds a profile, changes deployment topology, changes
token format, or expands discovery metadata.

## Assets

- Authorization codes
- Access tokens
- Refresh tokens
- ID Tokens
- DPoP proofs and nonces
- Client assertions
- Request objects and PAR handles
- User sessions and CSRF tokens
- Signing keys and JWKS metadata
- PostgreSQL durable state
- Valkey transient security state
- Discovery metadata
- Audit logs
- Signed Release manifests, artifact and OCI digests, and embedded build identity
- Deployment controller, receipt, audit, and break-glass identities
- Operator intent, runtime receipt, final receipt, and trust-transition chains
- Database backups and recovery metadata

## Trust Boundaries

| Boundary | Trusted side | Untrusted side | Required control |
| --- | --- | --- | --- |
| Browser to AS | AS endpoints | Browser, user-agent plugins, network attackers before TLS | HTTPS issuer, CSRF protection, redirect URI validation, PKCE |
| Client to AS | AS endpoints | OAuth clients, compromised clients, malicious clients | Client registration policy, client authentication, PAR/JAR validation |
| Reverse proxy to app | Configured trusted proxy CIDRs | Direct client traffic and untrusted proxies | `TRUSTED_PROXY_CIDRS`, header stripping, trusted internal channel |
| App to PostgreSQL | Application process | Database network and operators outside least privilege | credentials, network isolation, backups, migration controls |
| App to Valkey | Application process | Cache network and cache data loss | fail-closed replay/rate/session behavior |
| AS to resource server | Resource server verifier | Token replay and wrong-audience use | issuer/audience/cnf validation, revocation or introspection fallback |
| Host operator to target runtime | Root-owned `nazoauthctl` and registered deployment identity | Malicious local user, stale controller, wrong image/binary, replayed task | exact Release verification, actual OCI/binary digest, 60-second EdDSA envelope on stdin, embedded identity check, request claim and signed receipts |
| `nazoauthctl` to container engine | Reviewed typed lifecycle operations | Compromised daemon, mutable image name, over-broad mounts/network | signed image digest/revision check, operation-specific mount/network profile, non-root/read-only task container, no engine socket in task |
| `nazoauthctl` to host runtime | Root-owned config and verified binary | Untrusted service account and ambient host filesystem/network | actual binary digest, `systemd-run` transient unit, fixed user, protected filesystem, explicit read/write paths and address families |
| Controller identity to application task | Current controller public key and local persisted/configured deployment identity | Forged/expired/wrong-deployment/wrong-target envelope and retired key | fixed EdDSA/typ/kid/schema, exact `iss`/`aud`/`deployment_id` binding to local identity, closed claims, current trust key only, replay claim before mutation |
| Secret input to dependency/application | stdin/FD or root-owned secret mount | argv, ordinary environment, inspect, journal, audit and persisted JWS | secret-file/provider adapters, opaque revision or keyed HMAC binding, sanitized child errors |
| Release trust to deployment trust | Exact GitHub workflow identity and root-owned accepted-state record | downgrade, same-version substitution, controller impersonation | Sigstore bundle, closed manifest, SemVer anti-downgrade, separate controller transition chain |
| Break-glass identity to recovery | Independent root-owned recovery key and archived public history | missing/stolen controller and replay of old recovery material | explicit reason and confirmation, signed transition, atomic controller/audit/recovery rotation, old public key history only |
| Local audit to external observer | Signed/hash-linked local chain | host root able to delete or replace all local state | offline verification detects ordinary tamper; no immutability claim without a separately configured real external witness |

## Threats and Controls

| Threat | Risk | Controls | Operational note |
| --- | --- | --- | --- |
| Authorization code theft | Stolen code exchanged by attacker | PKCE S256, redirect URI matching, client binding, short TTL, atomic code consumption | Profile matrix tests for every high-security client class |
| Authorization code replay | Reuse races mint extra tokens | Valkey state machine, consumed-code token revocation | More concurrency and lost-response regression tests |
| Redirect mix-up | Token delivered to wrong client or endpoint | Exact redirect URI matching, issuer metadata, authorization response issuer support | Negative conformance fixtures for mix-up variants |
| JAR replay | Reused signed request object repeats authorization transaction | Signed object validation, optional `jti` replay state when present | Product hardening profile for mandatory request object `jti` |
| DPoP replay | Captured proof reused inside validity window | Proof `jti`, `htu`, `htm`, `ath`, nonce, JWK thumbprint, Valkey replay state | More explicit nonce profile tests and downgrade tests |
| mTLS header spoofing | Direct attacker forges forwarded certificate headers | mTLS evidence accepted only from trusted proxy CIDRs; duplicate/conflicting forwarded cert headers rejected | Require trusted proxy config in deployments, add proxy-to-app TLS guidance and live checks |
| Refresh token reuse | Stolen refresh token extends session | Opaque token hash storage, token family tracking, reuse detection | State-machine doc for lost-response retry; FAPI2 default no routine rotation |
| CSRF | Browser performs unwanted state-changing request | CSRF cookie/header check, SameSite cookies | Extend CSRF tests across all admin/profile mutation endpoints |
| XSS session theft | Script steals session credential | Session id only in HTTPOnly cookie; login JSON omits `session_id` | Frontend CSP and template audit |
| Key compromise | Signing key leak enables token forgery | Keyset validation, prepublished/active/grace/retired JWKS states, keyctl lifecycle, optional external KMS/HSM signer backend | Emergency rotation runbook and rehearsal evidence |
| Valkey outage | Replay/rate/session state unavailable | Sensitive paths fail with server errors instead of weakening controls | HA guidance, chaos tests, timeout SLOs |
| PostgreSQL outage | Durable state unavailable | Protocol endpoints return server errors | HA guidance, backup/restore tests, migration rollback plan |
| Metadata overclaim | Clients rely on unsupported security behavior | Discovery generated from runtime state for signing algs | Profile-aware metadata tests and conformance records |
| Operator task replay or response loss | A retry repeats a migration or key mutation | exact JTI/request-digest claim, application-owned receipt, ctl pending intent and final receipt recovery | An expired exact request may recover its existing receipt but cannot start new work |
| Target substitution | Signed request reaches a different artifact than the controller approved | ctl/runtime measures OCI image ID or host binary digest; app independently checks embedded Release/build identity; final receipt binds both | The application does not claim that it can prove its own OCI digest |
| Secret leakage through orchestration | Database, Valkey or private-key material appears in process metadata or logs | secret stdin/FD/mount/provider only, path-valued `*_FILE` environment, allowlisted audit schemas, sanitized process failures | Host root and a compromised engine remain able to inspect mounted secrets |
| Unsafe automatic rollback | Old code resumes against incompatible or irreversible schema | signed Release recovery policy distinguishes artifact rollback, schema-compatible rollback, backup/PITR restore and irreversible barrier | Database rollback is never described as automatic; `update --plan` states the actual boundary |
| Controller key loss or theft | Operations become unavailable or attacker signs tasks | mutations stop when signing fails; explicit break-glass transition replaces controller/audit/break-glass keys; runtime rejects old active key immediately | If wider host/dependency compromise is suspected, rotate those independent credentials too |

## Operator-control-plane modes and residual risk

- Managed production uses only `nazoauthctl` mutations and the fixed
  `nazoauth operator-task` entry point. The long-running database role has no
  DDL or temporary-table privilege.
- Source-tree Compose is an explicit development sandbox with an ephemeral
  development operator identity. It is not a production compatibility mode.
- External PostgreSQL/Valkey deployments keep backup/PITR and network-policy
  ownership outside NazoAuth; doctor and update plan must report that boundary.
- Online human approval and an external audit sink are not implemented without
  a real configured consumer. Local root is recorded as an actor category, not
  misrepresented as a natural-person identity.
- The file-backed controller and break-glass keys, container engine, host root,
  kernel, and firmware are outside the cryptographic protection boundary. A
  root or engine compromise can read mounted secrets and replace local evidence;
  signed local chains make ordinary tampering detectable but not externally
  immutable.

## Review Triggers

Update this threat model when:

- a new profile is added or advertised
- discovery metadata changes
- token format, `cnf`, or signing algorithms change
- reverse proxy or mTLS deployment topology changes
- refresh token rotation semantics change
- DCR, RAR, Device Grant, Token Exchange, federation, or SCIM is added
- production incident, conformance failure, or security report reveals a new class
