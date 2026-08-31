# Deployment Guide

NazoAuth has two explicit deployment contracts: Compose for source-based
development, and the signed `nazoauthctl` lifecycle for standalone Linux
production on Podman, Docker, or a host systemd service.

## Source-tree development sandbox

Requirements:

- Docker Engine or another Compose-compatible container runtime;
- Docker Compose v2.

From the repository root:

```sh
export NAZOAUTH_POSTGRES_PASSWORD='replace-with-a-unique-runtime-password'
export NAZOAUTH_POSTGRES_LIFECYCLE_PASSWORD='replace-with-a-different-lifecycle-password'
export NAZOAUTH_VALKEY_PASSWORD='replace-with-a-unique-valkey-password'
export NAZOAUTH_VALKEY_STATE_EPOCH='replace-with-a-new-uuid'
docker compose up -d --build
docker compose ps
```

Replace every placeholder before starting Compose. Passwords are embedded in
connection URLs, so restrict them to RFC 3986 unreserved characters
(`A-Z`, `a-z`, `0-9`, `-`, `.`, `_`, and `~`). Use a distinct lifecycle
password: the lifecycle role owns migrations, while the server connects as the
non-superuser runtime role. Compose passes `DATABASE_URL` and `VALKEY_URL`
directly to NazoAuth; it does not create application-specific URL or password
files. The PostgreSQL image creates the runtime role only when initializing a
new `postgres_data` volume, so changing these variables does not rotate an
existing database's credentials.

To change both the host port and the public origin seen by browsers, keep the
four variables above exported and run:

```sh
NAZOAUTH_PORT=443 \
NAZOAUTH_BIND_ADDRESS=0.0.0.0 \
NAZOAUTH_PUBLIC_BASE_URL=https://auth.example.com \
NAZOAUTH_TRANSPORT_MODE=trusted-proxy \
NAZOAUTH_TRUSTED_PROXY_CIDRS=<exact-ingress-peer-cidr> \
NAZOAUTH_MTLS_CERTIFICATE_SOURCE=disabled \
docker compose up -d --build
```

This remains a source development sandbox, not a signed, attested Release
installation.

`NAZOAUTH_BIND_ADDRESS=0.0.0.0` is required when a containerized Web IDE or
platform port mapper reaches the published host port through a non-loopback
interface. Keep the default `127.0.0.1` when a reverse proxy on the same host
terminates TLS. Do not bind all interfaces unless the platform or firewall
controls direct access to the plaintext port.

Compose maps `${NAZOAUTH_BIND_ADDRESS}:${NAZOAUTH_PORT}` on the host to the
server's container port `8000`. For example, `NAZOAUTH_BIND_ADDRESS=0.0.0.0
NAZOAUTH_PORT=6987` publishes host port `6987` to container port `8000`. A host
port of `443` in this example is only a port mapping: with
`TRANSPORT_MODE=trusted-proxy`, TLS is still terminated by the reverse proxy,
not by NazoAuth. The long-running Compose server runs as the unprivileged
container user `10001:10001`; the root `runtime-init` service only prepares
volume ownership and must not be used as the server process.

Replace `<exact-ingress-peer-cidr>` with the address NazoAuth observes for the
TLS terminator. The Compose path is a trusted-proxy deployment; it does not
mount the server certificate and client-CA files required by direct TLS.

Compose starts PostgreSQL and Valkey with the explicitly supplied credentials,
runs migrations through the lifecycle PostgreSQL role, and then starts the
server with the separate runtime role. Migration startup depends only on
PostgreSQL; Valkey readiness is required only by the server.
Open:

- `http://127.0.0.1:8000/health` for dependency readiness
- `http://127.0.0.1:8000/live` for process liveness
- `http://127.0.0.1:8000/.well-known/openid-configuration`

The first source build requires network access to download Rust dependencies.
Later builds reuse the local container cache.

The default is a loopback-only evaluation deployment. PostgreSQL, Valkey, and
application state—including signing keys, avatars, generated application secrets,
administrator-provisioning receipts, and the UI release cache—use named volumes and survive
`docker compose down`. Do not use `docker compose down -v` unless deleting all
local data is intentional.

When the database has no administrator, the managed flow invokes the target's
local `nazoauth admin-provision` one-shot command through
`nazoauthctl admin create`. Credentials are delivered through the
controller's protected credential path; the authorization server exposes no
HTTP bootstrap route or embedded setup page.

## Standalone Direct TLS

For a standalone deployment without a reverse proxy, write the following to
`.env.yaml` in the server working directory and run `nazoauth server` as a
dedicated unprivileged service account. Replace the database and Valkey
placeholders and the example UUIDv7 with deployment values. The certificate
must cover `auth.example.com`; the private key must be readable by the service
account and have no group or other permission bits.

```yaml
BIND: "0.0.0.0:8443"
TLS_BIND: "0.0.0.0:9443"
PUBLIC_BASE_URL: "https://auth.example.com:8443"
MTLS_ENDPOINT_BASE_URL: "https://auth.example.com:9443"
TRANSPORT_MODE: "direct-tls"
MTLS_CERTIFICATE_SOURCE: "direct-tls"
TLS_CERTIFICATE_FILE: "/etc/nazoauth/tls/server-chain.pem"
TLS_PRIVATE_KEY_FILE: "/etc/nazoauth/tls/server-key.pem"
TLS_CLIENT_CA_FILE: "/etc/nazoauth/tls/client-ca.pem"
TLS_RELOAD_INTERVAL_SECONDS: 5
DATABASE_URL: "postgresql://nazo_runtime:<password>@db.internal:5432/oauth"
VALKEY_URL: "redis://default:<password>@valkey.internal:6379/0"
VALKEY_STATE_EPOCH: "019c8ca2-30a6-7000-8000-00000000e102"
DATA_DIR: "/var/lib/nazoauth"
RUST_LOG: "info"
```

`BIND` and `TLS_BIND` use ports above 1024 so the long-running process does
not need root or `CAP_NET_BIND_SERVICE`; the root account is only needed to
provision files and directories. If clients must reach direct TLS on public
port 443, use an external port forward to these high ports or choose the
trusted-proxy deployment instead. Do not run the server as root just to bind a
privileged port. In `direct-tls`, NazoAuth terminates both HTTPS listeners and
gets the mTLS identity from the TLS session. In `trusted-proxy`, the proxy
terminates public TLS and NazoAuth receives only sanitized, authenticated
certificate evidence over the internal HTTP hop; the two modes are mutually
exclusive.

## Public deployment

For a formal release, prefer the lifecycle entry point:

```sh
nazoauthctl host add production-host --ssh production --privilege sudo
nazoauthctl install \
  --host production-host --name production \
  --runtime podman --public-url https://auth.example.com \
  --database-host db.internal --database-port 5432 \
  --database-name oauth \
  --database-runtime-user nazo_runtime \
  --database-runtime-password-file ./database-runtime-password \
  --database-lifecycle-user nazo_lifecycle \
  --database-lifecycle-password-file ./database-lifecycle-password \
  --valkey-host valkey.internal --valkey-port 6379 \
  --valkey-password-file ./valkey-password
nazoauthctl admin create --instance production
```

Select exactly one runtime: `podman`, `docker`, or `host`. The two PostgreSQL
roles and the Valkey credential must already exist; NazoAuthCtl does not create
credentials for external services. Target-local current-data import and backup
boundaries are documented in
[one-click installation and updates](one-click-update.md).

`nazoauthctl` generates the private server configuration, deployment identity,
signing identity, application secrets, and recovery state. It binds NazoAuth
to the selected host loopback port. Put any
standards-compliant TLS reverse proxy in front of
`http://127.0.0.1:8000`. Configure `TRUSTED_PROXY_CIDRS` only for proxy
addresses you control, and keep `CLIENT_IP_HEADER_MODE=none` until the proxy
sanitizes forwarded headers correctly.

Set `NAZOAUTH_PORT` when the host loopback port must differ. Changing the host
port does not change the issuer: `PUBLIC_BASE_URL` must still match the public
HTTPS address seen by clients.

### Reverse proxy and mTLS

When RFC 8705 or the full OIDF profile is enabled, the TLS terminator must
request a client certificate and forward it with the RFC 9440 `Client-Cert`
header. NazoAuth authenticates the certificate against the client registration;
the proxy must not accept a `Client-Cert` or `Client-Cert-Chain` value supplied
by the Internet client. Configure `MTLS_CERTIFICATE_SOURCE=rfc9440` and set
`TRUSTED_PROXY_CIDRS` to the exact address NazoAuth observes for that proxy. Do
not trust a whole container subnet when one host address is sufficient.

NazoAuthCtl conformance clients use a fresh CA and leaf certificate for every
run. A proxy in front of a conformance deployment therefore cannot advertise a
stale, fixed client-CA list. Install the public CA bundle generated for that run
before starting Suite modules and restore the previous bundle in the same run's
cleanup path. Use the reviewed HAProxy 3.2 boundary in
[`deploy/proxy/haproxy-rfc9440.cfg`](../../deploy/proxy/haproxy-rfc9440.cfg): it
separates ordinary HTTPS from a dedicated `verify required` mTLS listener,
strips all inbound forwarding and certificate headers, and adds only the
singleton RFC 9440 `Client-Cert` value derived from the verified TLS peer.

The leaf subject DN must differ from the CA subject DN, while its issuer DN must
match that CA. Include `openssl verify -CAfile run-ca.pem client.pem` in the
preflight; otherwise OpenSSL/HAProxy can classify a different-key leaf with the
same subject/issuer DN as self-signed and reject the handshake.

A client certificate must chain to the active bundle. NazoAuth still performs
the registration subject/SAN and optional certificate-digest checks. All of the
following must remain true:

- HAProxy deletes inbound certificate headers before adding its own value;
- the cleartext upstream is loopback-only or otherwise inaccessible to clients;
- NazoAuth trusts only the exact proxy address and validates the presented leaf
  against the registered certificate identity;
- TLS 1.2 and TLS 1.3 are restricted separately to the approved AES-GCM suites.

Build the run bundle only from the public `mtls_trust_anchor_pem` values bound to
the active lease. Write it atomically, validate the entire bundle, reload the
proxy, and confirm its digest before creating Suite modules. Cleanup restores
the previous bundle and reloads the proxy even after interruption. A shared
proxy must serialize this install/restore lifecycle unless each run has its own
listener and CA bundle. Never use `ca-ignore-err all` or `crt-ignore-err all` as
a production substitute for installing the run CA: that delegates all chain
trust to the application and can weaken RFC 8705 clients registered only by a
standard subject selector.

For ordinary production clients issued by a stable CA, install that CA in
HAProxy and use `verify required` on a dedicated mTLS listener. Do not combine
that listener with run-scoped conformance certificates unless the control plane
can atomically install and restore their CA.

Before reloading HAProxy, validate the candidate with the same HAProxy image or
binary (`haproxy -c -f /path/to/candidate.cfg`) and retain a root-only copy of
the previous configuration. After reload, verify `/health`, Discovery, the
unauthenticated Suite boundary, an allowed AES-GCM handshake, and rejection of
CBC and CHACHA20. Roll back the saved configuration and reload immediately if
any check fails.

## Validation

Activation requires all of these checks:

1. `nazoauthctl status` reports the signed Release and content-addressed target;
2. `nazoauthctl doctor` verifies audit, readiness, target digest, and the runtime DDL boundary;
3. `/health` returns HTTP 200;
4. `/.well-known/openid-configuration` returns the configured issuer;
5. the reverse proxy serves the same endpoints through the public HTTPS origin;
6. signing-key and avatar volumes remain mounted after a service restart.

Inspect the non-secret deployment state with:

```sh
nazoauthctl status
nazoauthctl operation --instance production --limit 20
```

## Upgrade and rollback

For a released standalone installation, the normal upgrade is:

```sh
nazoauthctl update --instance production
```

This verifies the tag-specific Sigstore identity and immutable artifact
digests, runs the signed migration and activation transaction, then checks
readiness and public Discovery. Configure a blocking backup gate explicitly:

```sh
nazoauthctl policy backup-before-update require --instance production \
  --max-age-seconds 86400
```

The gate refuses an update without the exact recent restore-tested snapshot.
If an irreversible migration has applied, artifact rollback is rejected and
the writer remains stopped until `nazoauthctl recover` restores a verified
snapshot. See
[One-click installation and updates](one-click-update.md).

Source deployments may still use Compose during development. They are not the
production update path. Database restoration remains separate because
migrations may be forward-only.

## Production boundaries

The bundled topology is a single-node deployment. Before relying on it for
production:

- back up the Compose database, Valkey state, and generated application secrets;
- retain the explicitly configured PostgreSQL and Valkey credentials in an
  appropriate secret manager;
- define backup and restore procedures;
- monitor PostgreSQL, Valkey, disk usage, and `/health`; use `/live` only for
  process restart decisions;
- keep signing keys and avatars on durable storage;
- use an external PostgreSQL/Valkey service or an orchestrator when HA is
  required;
- require the exact-commit security and conformance gates described in
  [release-security.md](release-security.md).

For an intentional clean-data replacement with OIDF-gated activation, use
[Fresh Deployment and Production Activation](fresh-production-activation.md).
Advanced settings are documented in [configuration.md](configuration.md).
